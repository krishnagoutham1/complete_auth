const {
  register,
  login,
  verifyEmail,
} = require("../controllers/authController");

const router = require("express").Router();

router.post("/login", login);
router.post("/register", register);
router.post("/verify/:token", verifyEmail);

module.exports = router;
