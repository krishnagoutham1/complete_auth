const dashboardUrl = `${process.env.CLIENT_URL}/dashboard`;

const updatePasswordUrl = (resetToken) =>
  `${process.env.CLIENT_URL}/auth/update-password/${resetToken}`;

const emailVerificationUrl = (activationToken) =>
  `${process.env.CLIENT_URL}/verify-email/${activationToken}`;

module.exports = {
  dashboardUrl,
  updatePasswordUrl,
  emailVerificationUrl,
};
