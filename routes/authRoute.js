const { register } = require("../controllers/authController");

const router = require("express").Router();

router.post("/login");
router.post("/register", register);
router.post("/verify-otp");

module.exports = router;
