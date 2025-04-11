const {
  register,
  verifyEmail,
  resendEmailVerification,
  login,
  verifyLoginOtp,
  resendLoginOtp,
  resetPasswordLink,
  updatePassword,
} = require("../controllers/authController");

const router = require("express").Router();

router.post("/register", register);
router.post("/verify-email/:token", verifyEmail);
router.post("/resend-email-verification", resendEmailVerification);

router.post("/login", login);
router.post("/verify-login-otp", verifyLoginOtp);
router.post("/resend-login-otp", resendLoginOtp);

router.post("/reset-password-link", resetPasswordLink);
router.post("/update-password", updatePassword);

module.exports = router;
