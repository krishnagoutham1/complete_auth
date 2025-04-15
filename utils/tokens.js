const jwt = require("jsonwebtoken");
const { JWT_EXPIRY } = require("./constants");

const generateEmailVerificationToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_EMAIL_VERIFICATION_SECRET, {
    expiresIn: JWT_EXPIRY.EMAIL_VERIFICATION,
  });
};

const generateResetPasswordToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_RESET_PASSWORD_SECRET, {
    expiresIn: JWT_EXPIRY.RESET_PASSWORD,
  });
};

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: JWT_EXPIRY.ACCESS_TOKEN,
  });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: JWT_EXPIRY.REFRESH_TOKEN,
  });
};

module.exports = {
  generateEmailVerificationToken,
  generateResetPasswordToken,
  generateAccessToken,
  generateRefreshToken,
};
