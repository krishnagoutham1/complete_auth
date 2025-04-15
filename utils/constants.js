const JWT_EXPIRY = {
  EMAIL_VERIFICATION: "10m",
  RESET_PASSWORD: "10m",
  ACCESS_TOKEN: "15m",
  REFRESH_TOKEN: "7d",
};

const REDIS_EXPIRY = {
  LOGIN_OTP: 15 * 60, // 900 seconds
  LOGIN_OTP_ATTEMPT: 15 * 60, // 900 seconds
  RESEND_OTP_ATTEMPT: 15 * 60, // 900 seconds
  RESEND_OTP_COOLDOWN: 60, // 1 minute
  REFRESH_TOKEN_ID: 7 * 24 * 60 * 60, // 7 days
  INVALIDATED_TOKEN: 10 * 60, // 10 minutes
};

const COOKIE_AGE = {
  ACCESS_TOKEN: 15 * 60 * 1000, // 15 minutes in ms
  REFRESH_TOKEN_ID: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
};

module.exports = { JWT_EXPIRY, REDIS_EXPIRY, COOKIE_AGE };
