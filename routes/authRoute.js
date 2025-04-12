const {
  register,
  verifyEmail,
  resendVerificationEmail,
  login,
  verifyLoginOtp,
  resendLoginOtp,
  sendResetPasswordLink,
  updatePassword,
  logout,
} = require("../controllers/authController");

const router = require("express").Router();

router.post("/register", register);
router.post("/email/verify/:token", verifyEmail);
router.post("/email/resend-verification", resendVerificationEmail);

router.post("/login", login);
router.post("/login/verify-otp", verifyLoginOtp);
router.post("/login/resend-otp", resendLoginOtp);

router.post("/password/reset-link", sendResetPasswordLink);
router.post("/password/update", updatePassword);

router.post("/logout", logout);

module.exports = router;
