const RedisKeys = {
  LOGIN_OTP: (userId) => `${userId}:login_otp`,
  LOGIN_OTP_ATTEMPT: (userId) => `${userId}:login_otp_attempt`,
  RESEND_OTP_ATTEMPT: (userId) => `${userId}:resend_otp_attempt`,
  RESEND_OTP_COOLDOWN: (userId) => `${userId}:resend_otp_cooldown`,
  REFRESH_TOKEN_ID: ({ userId, refreshId }) =>
    `${userId}:refresh_token:${refreshId}`,
  INVALIDATED_TOKEN: (token) => `invalid_token:${token}`,
};

module.exports = RedisKeys;
