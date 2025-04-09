const RedisKeys = {
  LOGIN_OTP: (userId) => `${userId}:loginOtp`,
  LOGIN_OTP_ATTEMPT: (userId) => `${userId}:loginOtpAttempt`,
  RESEND_OTP_ATTEMPT: (userId) => `${userId}:resendOtpAttempt`,
  RESEND_OTP_COOLDOWN: (userId) => `${userId}:resendOtpAttemptCooldown`,
  REFRESH_TOKEN_ID: ({ userId, refreshId }) =>
    `${userId}:refreshtoken_${refreshId}`,
};

module.exports = RedisKeys;
