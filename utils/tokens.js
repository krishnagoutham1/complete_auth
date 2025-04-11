const jwt = require("jsonwebtoken");

const generateEmailVerificationToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_ACTIVATION_SECRET, {
    expiresIn: "10m",
  });
};

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m",
  });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d",
  });
};

const getResePasswordToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_ACTIVATION_SECRET, {
    expiresIn: "15m",
  });
};

module.exports = {
  generateEmailVerificationToken,
  generateAccessToken,
  generateRefreshToken,
  getResePasswordToken,
};
