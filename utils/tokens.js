const jwt = require("jsonwebtoken");

const generateEmailVerificationToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_EMAIL_VERIFICATION_SECRET, {
    expiresIn: "10m",
  });
};

const generateResetPasswordToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_RESET_PASSWORD_SECRET, {
    expiresIn: "15m",
  });
};

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m",
  });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d",
  });
};

module.exports = {
  generateEmailVerificationToken,
  generateResetPasswordToken,
  generateAccessToken,
  generateRefreshToken,
};
