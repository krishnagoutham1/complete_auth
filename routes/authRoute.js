const {
  register,
  verifyEmail,
  resendEmailVerification,
  login,
  verifyLoginOtp,
  resendLoginOtp,
} = require("../controllers/authController");

const router = require("express").Router();

router.post("/register", register);
router.post("/verify/:token", verifyEmail);
router.post("/resend-emial-verification", resendEmailVerification);
router.post("/login", login);
router.post("/verify-login-otp", verifyLoginOtp);
router.post("/resend-login-otp", resendLoginOtp);

module.exports = router;
